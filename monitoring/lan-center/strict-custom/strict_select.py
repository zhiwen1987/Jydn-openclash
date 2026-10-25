"""Business-only activation: reject fence, close matching flows, then select private."""
import argparse,json,os,urllib.request,urllib.parse
from pathlib import Path
PREFIX={'node':'🔐 自定义节点 · ','group':'🔐 自定义节点组 · '}
SHARED={kind:'🔐 自定义节点' for kind in PREFIX}
ALLOWED=('🔐 自建节点 · ','🔐 自建节点池 · ')
FORBIDDEN={'Direct','Pass','Compatible','Dns','Selector','URLTest','Fallback','LoadBalance','Relay'}
def activate(api,business,kind,target='REJECT'):
 wrapper=SHARED[kind];proxies=api('/proxies')['proxies']
 outer=proxies.get(business,{});inner=proxies.get(wrapper,{})
 if outer.get('type')!='Selector' or wrapper not in outer.get('all',[]):raise ValueError('business_not_prepared')
 members=inner.get('all',[])
 if inner.get('type')!='Selector' or not members or members[0]!='REJECT':raise ValueError('strict_wrapper_invalid')
 if any(n in {'DIRECT','PASS','COMPATIBLE','GLOBAL'} or proxies.get(n,{}).get('type') in FORBIDDEN and not n.startswith(ALLOWED) for n in members):raise ValueError('unsafe_group_or_bypass_member')
 if target not in members:raise ValueError('target_not_approved')
 def select(group,node):
  path='/proxies/'+urllib.parse.quote(group,safe='')
  api(path,'PUT',{'name':node})
  if api(path).get('now')!=node:raise RuntimeError('selection_readback_failed_left_closed')
 # Changing a shared target fences and drains every current subscriber.
 select(wrapper,'REJECT');select(business,wrapper)
 closed=[]
 for _ in range(3):
  if api('/proxies/'+urllib.parse.quote(business,safe='')).get('now')!=wrapper:raise RuntimeError('concurrent_manual_change')
  rows=api('/connections').get('connections') or []
  matches=[v for v in rows if business in v.get('chains',[]) or wrapper in v.get('chains',[])]
  if not matches:break
  for row in matches:
   cid=row['id'];api('/connections/'+urllib.parse.quote(cid,safe=''),'DELETE');closed.append(cid)
 else:raise RuntimeError('connections_not_drained_left_closed')
 if api('/proxies/'+urllib.parse.quote(business,safe='')).get('now')!=wrapper:raise RuntimeError('concurrent_manual_change')
 select(wrapper,target)
 return {'business':business,'wrapper':wrapper,'selected':target,'matching_connections_closed':len(closed),'closed_until_configured':target=='REJECT'}
def main():
 import fcntl
 p=argparse.ArgumentParser();p.add_argument('--business',required=True);p.add_argument('--kind',choices=list(PREFIX),required=True);p.add_argument('--target',default='REJECT');args=p.parse_args()
 endpoint=os.environ['OPENCLASH_API'].rstrip('/');secret=os.environ['OPENCLASH_SECRET'];op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 def api(path,method='GET',body=None):
  req=urllib.request.Request(endpoint+path,method=method,data=json.dumps(body,ensure_ascii=False).encode() if body is not None else None,
   headers={'Authorization':'Bearer '+secret,'Content-Type':'application/json'})
  with op.open(req,timeout=10) as r:raw=r.read()
  return json.loads(raw) if raw else {}
 lock=Path('/data/routing-owner.lock');lock.parent.mkdir(parents=True,exist_ok=True)
 with lock.open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  print(json.dumps(activate(api,args.business,args.kind,args.target),ensure_ascii=False))
if __name__=='__main__':main()
