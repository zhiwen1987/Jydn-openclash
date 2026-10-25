"""Shared template names; private credentials are never a build input."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NODE_PREFIX='🔐 自定义节点 · '
GROUP_PREFIX='🔐 自定义节点组 · '
def choices(name):return (NODE_PREFIX+name,GROUP_PREFIX+name)
def policy():return json.loads((ROOT/'modules/strict-custom-policy.json').read_text(encoding='utf-8'))
def add_entries(text):
 targets=set(policy()['business_groups']);output=[];groups=[]
 for line in text.splitlines():
  if line.startswith('custom_proxy_group='):
   name=line.split('=',1)[1].split('`',1)[0]
   if name in targets:
    for child in choices(name):line+='`[]'+child;groups.append('custom_proxy_group='+child+'`select`[]REJECT')
  output.append(line)
 return '\n'.join(output+['','; >>> strict private empty entries (REJECT until configured) <<<']+groups)
