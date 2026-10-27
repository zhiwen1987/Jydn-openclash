"""Measure a real provider node without changing any selector or group pin."""
from datetime import datetime
import time
import urllib.parse

TARGETS = ('https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204')
_inventory = (0, {})
_failures=[]
_paused_until=0


def batch_paused(epoch=None):
    return (time.time() if epoch is None else epoch)<_paused_until


def suspect_batch(entry,result,epoch):
    global _failures
    _failures=[r for r in _failures if 0<=epoch-r[0]<120]
    _failures.append((epoch,entry['id'],entry.get('provider',''),bool(result['success'])))
    return (len({r[1] for r in _failures})>=4 and len({r[2] for r in _failures})>=2
            and not any(r[3] for r in _failures))


def pause_batch(epoch):
    global _paused_until,_failures
    _paused_until=epoch+60;_failures=[]


def quote(value):
    return urllib.parse.quote(value, safe='')


def parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0


def inventory(api, epoch=None):
    global _inventory
    epoch=time.time() if epoch is None else epoch
    if not 0 <= epoch-_inventory[0] < 5:
        _inventory=(epoch, api('/providers/proxies').get('providers', {}))
    return _inventory[1]


def measure(api, entry, epoch, timeout=5000, force=False):
    provider=entry.get('provider');name=entry['name']
    if not provider:
        return {'success':False,'error_category':'detector_provider_unknown','origin':'clash','latency':0,'observed_at':epoch}
    try:
        proxies=inventory(api,epoch).get(provider,{}).get('proxies',[])
        proxy=next((v for v in proxies if v.get('name')==name),None)
        if proxy is None:
            return {'success':False,'error_category':'detector_node_not_loaded','origin':'clash','latency':0,'observed_at':epoch}
        # Only reuse the explicitly indexed HTTPS target, not an unknown default
        # health-check URL (which may be HTTP or measure a different destination).
        extra=proxy.get('extra',{}).get(TARGETS[0],{})
        histories=extra.get('history',[]) if isinstance(extra,dict) else []
        if histories and not force:
            h=histories[-1];stamp=parse_time(h.get('time'));delay=h.get('delay')
            if type(delay) in (int,float) and delay>0 and 0<=epoch-stamp<300:
                return {'success':True,'latency':float(delay),'observed_at':stamp,'origin':'clash_history','error_category':'ok','code':0,'content_type':'','error':'','probe':'clash_https'}
        # The provider-specific endpoint resolves nodes absent from /proxies.
        # Never use group/delay: upstream documents that it clears fixed choices.
        path='/providers/proxies/'+quote(provider)+'/'+quote(name)+'/healthcheck'
        results=[]
        for target in TARGETS:
            try:
                r=api(path+'?'+urllib.parse.urlencode({'url':target,'timeout':timeout}))
                delay=r.get('delay')
                if type(delay) not in (int,float) or not 0<delay<=timeout:
                    raise ValueError('invalid_delay')
                return {'success':True,'latency':float(delay),'observed_at':time.time(),'origin':'clash_api','error_category':'ok','code':0,'content_type':'','error':'','probe':'clash_https'}
            except Exception as e:
                status=getattr(e,'code',None)
                if status in (401,403,404):
                    return {'success':False,'latency':0,'observed_at':epoch,'origin':'clash','error_category':'detector_api_unavailable','probe':'clash_https'}
                if status not in (503,504):
                    return {'success':False,'latency':0,'observed_at':epoch,'origin':'clash','error_category':'detector_transport_unavailable','probe':'clash_https'}
                results.append(status)
        try:
            if not isinstance(api('/version').get('version'),str):raise ValueError('control_health_unknown')
        except Exception:
            return {'success':False,'latency':0,'observed_at':epoch,'origin':'clash','error_category':'detector_control_unavailable','probe':'clash_https'}
        return {'success':False,'latency':0,'observed_at':time.time(),'origin':'clash_api','error_category':'timeout','code':0,'content_type':'','error':'timeout','probe':'clash_https'}
    except Exception:
        return {'success':False,'latency':0,'observed_at':epoch,'origin':'clash','error_category':'detector_inventory_unavailable','probe':'clash_https'}
