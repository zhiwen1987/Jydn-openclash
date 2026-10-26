"""Pure release admission and scheduling decisions; no network or state writes."""
import re

METADATA = re.compile(r'订阅地址失效|订阅(?:已)?过期|请到网站|使用教程|剩余流量|重置剩余|下次重置|套餐到期|官网|刷新订阅|刷新失败|更新失败|Expire|Traffic|Reset|Remaining|Official|Website',re.I)
# This is the currently reviewed provider exclusion policy, not a guessed parser.
KERNEL_EXCLUDE = re.compile(r'流量|套餐|到期|剩余|重置|官网|网站|最新网址|防失联|失联|官网地址|公告|通知|TG|Telegram|电报|群|频道|说明|使用说明|QQ群|客服|工单|订阅|Expire|Traffic|Reset|Remaining|Official|Website',re.I)

def usable_name(name):
 return bool(name and not METADATA.search(name) and not KERNEL_EXCLUDE.search(name))

def next_probe_due(state,fresh_until,updated_at,failures,base=300,maximum=3600):
 if state in {'unavailable','cooling'} and failures>=2:
  return max(int(fresh_until or 0),int(updated_at or 0)+min(maximum,base*2**min(max(0,int(failures)-1),5)))
 return int(fresh_until or 0)

def budget_allows(events,now,component,limit=2,window=1800):
 if any(e.get('at',now)>now for e in events):return False
 return sum(e.get('component')==component and 0<=now-e.get('at',0)<window for e in events)<limit
