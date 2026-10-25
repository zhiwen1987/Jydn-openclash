"""Shared template names; private credentials are never a build input."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NODE_PREFIX='🔐 自定义节点 · '
GROUP_PREFIX='🔐 自定义节点组 · '
def choices(name=None):return ('🔐 自定义节点',)
NODE_FILTER='(?i)^(?!.*(剩余流量|重置剩余|下次重置|套餐到期|官网|邮箱|节点异常|刷新订阅|刷新失败|更新失败|取消订阅时限)).+'

def entry_definition(name):
 return 'custom_proxy_group='+name+'`select`[]REJECT'+('`'+NODE_FILTER if policy().get('select_all_nodes') else '')
def policy():return json.loads((ROOT/'modules/strict-custom-policy.json').read_text(encoding='utf-8'))
def add_entries(text):
 targets=set(policy()['business_groups']);output=[]
 for line in text.splitlines():
  if line.startswith('custom_proxy_group='):
   name=line.split('=',1)[1].split('`',1)[0]
   if name in targets:
    for child in choices(name):line+='`[]'+child
  output.append(line)
 groups=[entry_definition(child) for child in choices()]
 return '\n'.join(output+['','; >>> shared private empty entries (REJECT until configured) <<<']+groups)
