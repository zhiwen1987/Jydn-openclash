"""Apply narrow extension hooks to captured, existing runtime sources.

No replacement of older deployed admission/quality/autonomy implementations.
This utility fails if an expected source anchor changes upstream.
"""
import hashlib
from pathlib import Path


def patch_subscription(text):
    if 'from local_web import install' in text:
        return text
    anchor = '    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)'
    if text.count(anchor) != 1:
        raise ValueError('subscription_hook_anchor_changed')
    return text.replace(anchor, '    __import__("sys").path.insert(0, "/local-subscription")\n    from local_web import install\n    install(globals())\n' + anchor)


def patch_capability(text):
    if 'last_local_generation' in text:
        return text
    start = '    last_discovery = 0\n'
    condition = '            if not nodes or epoch - last_discovery >= DISCOVERY_INTERVAL:\n'
    update = '                last_discovery = epoch\n'
    if any(text.count(anchor) != 1 for anchor in (start, condition, update)):
        raise ValueError('capability_hook_anchor_changed')
    text = text.replace(start, start + '    last_local_generation = 0\n')
    text = text.replace(condition,
        '            local_trigger = DB_PATH.parent / "local-discovery.json"\n'
        '            local_generation = local_trigger.stat().st_mtime_ns if local_trigger.exists() else 0\n'
        '            if not nodes or local_generation != last_local_generation or epoch - last_discovery >= DISCOVERY_INTERVAL:\n')
    return text.replace(update, update + '                last_local_generation = local_generation\n')


def prepare(source, destination):
    source, destination = Path(source), Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    receipt = {}
    for filename, patch in [('subscription-controller.py', patch_subscription), ('node-capability.py', patch_capability)]:
        raw = (source / filename).read_text(encoding='utf-8')
        changed = patch(raw)
        compile(changed, filename, 'exec')
        path = destination / filename
        path.write_text(changed, encoding='utf-8')
        receipt[filename] = {'before': hashlib.sha256(raw.encode()).hexdigest(), 'after': hashlib.sha256(changed.encode()).hexdigest()}
    return receipt
