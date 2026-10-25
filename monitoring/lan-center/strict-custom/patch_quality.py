"""Asserted overlay for the deployed quality controller; no source guessing."""
from pathlib import Path
def patch(text):
 future='from __future__ import annotations\n'
 if text.count(future)!=1:raise ValueError('unsupported_quality_imports')
 text=text.replace(future,future+'from strict_custom_guard import is_strict_path\n')
 anchor='lease=policy.get("manual_override_seconds",0)'
 if text.count(anchor)!=1:raise ValueError('unsupported_quality_source')
 text=text.replace(anchor,'lease=0 if is_strict_path(proxies,outer) else policy.get("manual_override_seconds",0)')
 # This marker makes the exact suppression visible in the live state and tests.
 marker='info.update(current=current, manual_override=bool(manual), candidates=candidates)'
 if text.count(marker)!=1:raise ValueError('unsupported_quality_state_source')
 return text.replace(marker,'info.update(current=current, manual_override=bool(manual), strict_locked=is_strict_path(proxies,outer), candidates=candidates)')
if __name__=='__main__':
 import sys
 source,destination=map(Path,sys.argv[1:]);value=patch(source.read_text());compile(value,str(destination),'exec');destination.write_text(value)
