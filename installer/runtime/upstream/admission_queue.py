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
        manifest=module.current_manifest();published=module.previous_fingerprints(manifest);candidates={};source_stats={}
        published_by_source={str(row.get('id')):len(row.get('approved_fingerprints',[]))
                             for row in (manifest or {}).get('source_breakdown',[]) if isinstance(row,dict)}
        for source in module.load_sources():
            p=module.CACHE/(source.source_id+'.yaml')
            if not p.is_file() or p.stat().st_size>module.MAX_BYTES:continue
            nodes=module.normalized_nodes(module.parse_nodes(p.read_bytes()))
            stats=source_stats.setdefault(source.source_id,{
                'source_id':source.source_id,'parsed_count':len(nodes),'candidate_count':0,
                'published_count':published_by_source.get(source.source_id,0),
                'approved_count':published_by_source.get(source.source_id,0),
            })
            for node in nodes:
                fingerprint=module.fingerprint(node)
                if fingerprint not in published:
                    item=candidates.setdefault(fingerprint,{'node':node,'sources':set()})
                    item['sources'].add(source.source_id);stats['candidate_count']+=1
        pending=sorted(
            ((due(cache.get(fp,{}),epoch),fp,item) for fp,item in candidates.items() if due(cache.get(fp,{}),epoch)<=epoch),
            key=lambda row:row[:2],
        )
        batch_size=max(1,min(2,int(os.getenv('SUBSCRIPTION_ADMISSION_BATCH_SIZE','2'))))
        if not pending:
            for fp,item in candidates.items():
                record=cache.get(fp,{})
                for source_id in item['sources']:
                    stats=source_stats[source_id]
                    stats['tested_count']=stats.get('tested_count',0)+int(bool(record.get('last_attempt')))
                    next_due=due(record,epoch)
                    stats['next_due']=min(stats.get('next_due',next_due),next_due)
                    stats['approved_count']=stats.get('approved_count',0)+int(eligible(record,epoch))
                    stats['queued_count']=stats.get('queued_count',0)+int(not eligible(record,epoch))
                    stats['cooling_count']=stats.get('cooling_count',0)+int(record.get('status')=='unavailable' and next_due>epoch)
                    stats['due_count']=stats.get('due_count',0)+int(next_due<=epoch)
            atomic(state_dir/'admission-progress.json',{
                'schema':1,'epoch':epoch,'batch_limit':batch_size,'pending_count':0,
                'detector_scope':'loopback_isolated_core','candidate_exposed':False,
                'sources':sorted(source_stats.values(),key=lambda row:row['source_id']),
            })
            return False
        if validator is None:
            from node_admission import validate
            validator=validate
        source_ids=sorted(source_stats)
        try:source_cursor=int(json.loads(clock.read_text()).get('source_cursor',0))
        except (OSError,ValueError,TypeError):source_cursor=0
        source_cursor=source_cursor%len(source_ids) if source_ids else 0
        source_order=source_ids[source_cursor:]+source_ids[:source_cursor]
        selected=[];selected_fp=set()
        # Prefer one due node from each source before giving spare capacity to
        # another node. Shared fingerprints count for every owning source.
        for source_id in source_order:
            match=next((row for row in pending if row[1] not in selected_fp and source_id in row[2]['sources']),None)
            if match:
                selected.append(match);selected_fp.add(match[1])
                if len(selected)>=batch_size:break
        if len(selected)<batch_size:
            selected.extend(row for row in pending if row[1] not in selected_fp)
            selected=selected[:batch_size]
        promoted=[];finished=epoch
        # No SQLite write transaction or routing lock spans an external test.
        # A tiny bounded batch improves first-use latency without unbounded
        # processes or concurrent temporary Mihomo cores.
        for _due_at,fp,item in selected:
            node=item['node']
            ok,reason=validator(node);finished=epoch if explicit_epoch else int(time.time())
            previous=cache.get(fp,{})
            # Legacy success caches had no recovery streak; do not silently promote.
            cache[fp]=transition(previous,ok,finished,reason)
            if not eligible(previous,epoch) and eligible(cache[fp],finished):
                promoted.extend(item['sources'])
        # Cache never stores node credentials/addresses, only fingerprints/state.
        keep=set(candidates)|published
        cache={k:v for k,v in cache.items() if k in keep}
        for fp,item in candidates.items():
            record=cache.get(fp,{})
            for source_id in item['sources']:
                stats=source_stats[source_id]
                stats['tested_count']=stats.get('tested_count',0)+int(bool(record.get('last_attempt')))
                next_due=due(record,finished)
                stats['next_due']=min(stats.get('next_due',next_due),next_due)
                stats['approved_count']=stats.get('approved_count',0)+int(eligible(record,finished))
                stats['queued_count']=stats.get('queued_count',0)+int(not eligible(record,finished))
                stats['cooling_count']=stats.get('cooling_count',0)+int(record.get('status')=='unavailable' and next_due>finished)
                stats['due_count']=stats.get('due_count',0)+int(next_due<=finished)
        atomic(cache_path,cache)
        next_cursor=(source_cursor+max(1,len(selected)))%len(source_ids) if source_ids else 0
        atomic(clock,{'last_attempt':finished,'last_scope':error_scope(reason),'candidate_count':len(candidates),
                      'batch_count':len(selected),'source_cursor':next_cursor})
        atomic(state_dir/'admission-progress.json',{
            'schema':1,'epoch':finished,'batch_limit':batch_size,
            'pending_count':sum(1 for fp in candidates if due(cache.get(fp,{}),finished)<=finished),
            'detector_scope':'loopback_isolated_core','candidate_exposed':False,
            'sources':sorted(source_stats.values(),key=lambda row:row['source_id']),
        })
        if promoted:
            atomic(module.DATA/'reconcile-request.json',{
                'schema':1,'owner':'admission-queue','requested_at':finished,'source_id':sorted(promoted)[0],
            })
        return True
