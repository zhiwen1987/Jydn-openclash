"""Strict selectors are permanent manual selections; no expiring auto takeover."""
PREFIXES=('🔐 自定义节点 · ','🔐 自定义节点组 · ')
def is_strict_selection(name):
 return isinstance(name,str) and (name == '🔐 自定义节点' or name.startswith(PREFIXES))
def is_strict_path(proxies,outer):
 seen=set();name=outer
 while isinstance(name,str) and name not in seen:
  if is_strict_selection(name) or name.startswith(('🔐 自建节点 · ','🔐 自建节点池 · ')):return True
  seen.add(name);name=proxies.get(name,{}).get('now')
 return False
def may_reclaim(selection,policy):
 return not is_strict_selection(selection) and bool(policy.get('manual_override_seconds',0))
